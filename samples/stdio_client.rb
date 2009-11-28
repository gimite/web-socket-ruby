# Copyright: Hiroshi Ichikawa <http://gimite.net/en/>
# Lincense: New BSD Lincense

$LOAD_PATH << "./lib"
require "web_socket"

client = WebSocket.new(ARGV[0] || "ws://localhost:10081/")
puts("Ready")
Thread.new() do
  while data = client.receive()
    printf("Received: %p\n", data)
  end
end
$stdin.each_line() do |line|
  data = line.chomp()
  client.send(data)
  printf("Sent: %p\n", data)
end
