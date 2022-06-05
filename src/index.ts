import parseRange from "range-parser";
import mime from "mime";

interface Env {
  R2_BUCKET: R2Bucket,
  AUTH_SECRET?: string,
  CACHE_CONTROL?: string
}

type ParsedRange = { offset: number, length: number } | { suffix: number };

function hasBody(object: R2Object | R2ObjectBody): object is R2ObjectBody {
  return (<R2ObjectBody>object).body !== undefined;
}

function hasSuffix(range: ParsedRange): range is { suffix: number } {
  return (<{ suffix: number }>range).suffix !== undefined;
}

function getRangeHeader(range: ParsedRange, fileSize: number): string {
  return `bytes ${hasSuffix(range) ? (fileSize - range.suffix) : range.offset}-${hasSuffix(range) ? fileSize - 1 :
    (range.offset + range.length - 1)}/${fileSize}`;
}

function canWrite(request: Request, env: Env): boolean {
  if (!request.headers.get('Authorization') || !env.AUTH_SECRET) {
    return false;
  }

  const authorization = request.headers.get('Authorization') ?? "";
  const [scheme, encoded] = authorization.split(' ');
  // The Authorization header must start with Basic, followed by a space.
  if (!encoded || scheme !== 'Basic') {
    return false;
  }
  // Decodes the base64 value and performs unicode normalization.
  // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
  // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
  const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
  const decoded = new TextDecoder().decode(buffer).normalize();

  // Allow the secret to appear in user or pass. Just so long as it's in there.
  return decoded.includes(env.AUTH_SECRET);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if ('https:' !== url.protocol || 'https' !== request.headers.get('x-forwarded-proto')) {
      return new Response("Must use HTTPS", { status: 401 });
    }

    let path = decodeURIComponent(url.pathname.substring(1));
    if (path.length > 0 && path.slice(-1) == '/') {
      console.warn("Appending index.html to", path);
      path += "index.html";
    }

    if (canWrite(request, env)) {
      console.info("Authenticated", request.method, "request to", path);
      switch (request.method) {
        case "PUT":
          await env.R2_BUCKET.put(path, request.body);
          return new Response(`Uploaded ${path}`);
        case "DELETE":
          await env.R2_BUCKET.delete(path);
          return new Response(`Deleted ${path}`, { status: 200 });
      }
    }

    const allowedMethods = ["GET", "HEAD", "OPTIONS"];
    if (allowedMethods.indexOf(request.method) === -1) return new Response("Method Not Allowed", { status: 405 });

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { "allow": allowedMethods.join(", ") } })
    }

    const cache = caches.default;
    let response = await cache.match(request);

    // Since we produce this result from the request, we don't need to strictly use an R2Range
    let range: ParsedRange | undefined;

    if (!response || !response.ok) {
      console.warn("Cache miss on", path);
      if (url.pathname === "/" || url.pathname == "/index.html") {
        return new Response("OK");
      }

      let file: R2Object | R2ObjectBody | null | undefined;

      // Range handling
      if (request.method === "GET") {
        const rangeHeader = request.headers.get("range");
        if (rangeHeader) {
          file = await env.R2_BUCKET.head(path);
          if (file === null) return new Response("File Not Found", { status: 404 });
          const parsedRanges = parseRange(file.size, rangeHeader);
          // R2 only supports 1 range at the moment, reject if there is more than one
          if (parsedRanges !== -1 && parsedRanges !== -2 && parsedRanges.length === 1 && parsedRanges.type === "bytes") {
            let firstRange = parsedRanges[0];
            range = file.size === (firstRange.end + 1) ? { suffix: file.size - firstRange.start } : {
              offset: firstRange.start,
              length: firstRange.end - firstRange.start + 1
            }
          } else {
            return new Response("Range Not Satisfiable", { status: 416 });
          }
        }
      }

      // Etag/If-(Not)-Match handling
      // R2 requires that etag checks must not contain quotes, and the S3 spec only allows one etag
      // This silently ignores invalid or weak (W/) headers
      const getHeaderEtag = (header: string | null) => header?.trim().replace(/^['"]|['"]$/g, "");
      const ifMatch = getHeaderEtag(request.headers.get("if-match"));
      const ifNoneMatch = getHeaderEtag(request.headers.get("if-none-match"));

      const ifModifiedSince = Date.parse(request.headers.get("if-modified-since") || "");
      const ifUnmodifiedSince = Date.parse(request.headers.get("if-unmodified-since") || "");

      const ifRange = request.headers.get("if-range");
      if (range && ifRange && file) {
        const maybeDate = Date.parse(ifRange);

        if (isNaN(maybeDate) || new Date(maybeDate) > file.uploaded) {
          // httpEtag already has quotes, no need to use getHeaderEtag
          if (ifRange.startsWith("W/") || ifRange !== file.httpEtag) range = undefined;
        }
      }

      if (ifMatch || ifUnmodifiedSince) {
        file = await env.R2_BUCKET.get(path, {
          onlyIf: {
            etagMatches: ifMatch,
            uploadedBefore: ifUnmodifiedSince ? new Date(ifUnmodifiedSince) : undefined
          }, range
        });

        if (file && !hasBody(file)) {
          return new Response("Precondition Failed", { status: 412 });
        }
      }

      if (ifNoneMatch || ifModifiedSince) {
        // if-none-match overrides if-modified-since completely
        if (ifNoneMatch) {
          file = await env.R2_BUCKET.get(path, { onlyIf: { etagDoesNotMatch: ifNoneMatch }, range });
        } else if (ifModifiedSince) {
          file = await env.R2_BUCKET.get(path, { onlyIf: { uploadedAfter: new Date(ifModifiedSince) }, range });
        }
        if (file && !hasBody(file)) {
          return new Response(null, { status: 304 });
        }
      }

      file = request.method === "HEAD"
        ? await env.R2_BUCKET.head(path)
        : ((file && hasBody(file)) ? file : await env.R2_BUCKET.get(path, { range }));

      if (file === null) {
        return new Response("File Not Found", { status: 404 });
      }

      response = new Response(hasBody(file) && (file?.size > 0) ? file.body : null, {
        status: (file?.size || 0) === 0 ? 204 : (range ? 206 : 200),
        headers: {
          "accept-ranges": "bytes",

          "etag": file.httpEtag,
          "cache-control": file.httpMetadata.cacheControl ?? (env.CACHE_CONTROL || ""),
          "expires": file.httpMetadata.cacheExpiry?.toUTCString() ?? "",
          "last-modified": file.uploaded.toUTCString(),

          "content-encoding": file.httpMetadata?.contentEncoding ?? "",
          "content-type": file.httpMetadata?.contentType ?? (mime.getType(file.key) || "application/octet-stream"),
          "content-language": file.httpMetadata?.contentLanguage ?? "",
          "content-disposition": file.httpMetadata?.contentDisposition ?? "",
          "content-range": range ? getRangeHeader(range, file.size) : "",
        }
      });

      if (request.method === "GET" && !range)
        ctx.waitUntil(cache.put(request, response.clone()));
    }

    return response;
  },
};
