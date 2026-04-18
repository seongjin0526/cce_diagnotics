const http = require("http");

const server = http.createServer((_req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("nodejs lab\n");
});

server.listen(3000, "0.0.0.0");
