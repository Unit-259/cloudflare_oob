export default {
  async fetch(request, env, ctx) {
    // Current timestamp
    const time = new Date().toISOString();

    // Basic request info
    const url = new URL(request.url);
    const method = request.method;

    // Grab a few core headers
    const ip = request.headers.get("cf-connecting-ip") || "no-ip";
    const userAgent = request.headers.get("user-agent") || "no-agent";

    // Log basic information for verification
    console.log(JSON.stringify({
      event: "OOB Trigger",
      time,
      method,
      url: url.toString(),
      ip,
      userAgent
    }));

    // Return a simple response
    return new Response("OK", {
      status: 200,
      headers: {
        "Content-Type": "text/plain",
        "Cache-Control": "no-store"
      }
    });
  }
}
