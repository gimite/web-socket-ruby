# Copyright: Hiroshi Ichikawa <http://gimite.net/en/>
# Lincense: New BSD Lincense

$LOAD_PATH << "./lib"
require "web_socket"

Thread.abort_on_exception = true

server = WebSocketServer.new(
  ARGV[0] || "ws://localhost:10081",
  :host => "0.0.0.0")
puts("Ready")
server.run() do |ws|
  puts("Connection accepted")
  puts("Path: #{ws.path}, Origin: #{ws.origin}")
  if ws.path == "/"
    ws.handshake()
    while data = ws.receive()
      printf("Received: %p\n", data)
      ws.send(data)
      printf("Sent: %p\n", data)
    end
  else
    ws.handshake("404 Not Found")
  end
  puts("Connection closed")
end
