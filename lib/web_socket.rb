# Copyright: Hiroshi Ichikawa <http://gimite.net/en/>
# Lincense: New BSD Lincense
# Reference: http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-31

require "socket"
require "uri"


if RUBY_VERSION < "1.9.0"
  
  class String
      
      def force_encoding(encoding)
        return self
      end
      
      def ord
        return self[0]
      end
      
      alias bytesize size
      
  end
  
  class Integer
      
      def ord
        return self
      end
      
  end
  
end


class WebSocket
    
    class Error < RuntimeError
    
    end
    
    def initialize(arg, params = {})
      if params[:server] # server
        
        @server = params[:server]
        @socket = arg
        line = @socket.gets().chomp()
        if !(line =~ /\AGET (\S+) HTTP\/1.1\z/n)
          raise(WebSocket::Error, "invalid request: #{line}")
        end
        @path = $1
        read_header()
        if !@server.accepted_origin?(self.origin)
          raise(WebSocket::Error, "unaccepted origin: %s (server.accepted_domains = %p)" %
            [self.origin, @server.accepted_domains])
        end
        @handshaked = false
        
      else # client
        
        uri = arg.is_a?(String) ? URI.parse(arg) : arg
        if uri.scheme == "wss"
          raise(WebSocket::Error, "wss scheme is unimplemented")
        elsif uri.scheme != "ws"
          raise(WebSocket::Error, "unsupported scheme: #{uri.scheme}")
        end
        @path = (uri.path.empty? ? "/" : uri.path) + (uri.query ? "?" + uri.query : "")
        origin = params[:origin] || "http://#{uri.host}"
        @socket = TCPSocket.new(uri.host, uri.port || 80)
        @socket.write(
          "GET #{@path} HTTP/1.1\r\n" +
          "Upgrade: WebSocket\r\n" +
          "Connection: Upgrade\r\n" +
          "Host: #{uri.host}\r\n" +
          "Origin: #{origin}\r\n" +
          "\r\n")
        @socket.flush()
        line = @socket.gets().chomp()
        raise(WebSocket::Error, "bad response: #{line}") if !(line =~ /\AHTTP\/1.1 101 /n)
        read_header()
        if @header["WebSocket-Origin"] != origin
          raise(WebSocket::Error,
            "origin doesn't match: '#{@header["WebSocket-Origin"]}' != '#{origin}'")
        end
        @handshaked = true
        
      end
      @received = []
      @buffer = ""
    end
    
    attr_reader(:server, :header, :path)
    
    def handshake(status = nil, header = {})
      if @handshaked
        raise(WebSocket::Error, "handshake has already been done")
      end
      status ||= "101 Web Socket Protocol Handshake"
      def_header = {
        "Upgrade" => "WebSocket",
        "Connection" => "Upgrade",
        "WebSocket-Origin" => origin,
        "WebSocket-Location" => @server.uri + @path,
      }
      header = def_header.merge(header)
      header_str = header.map(){ |k, v| "#{k}: #{v}\r\n" }.join("")
      @socket.write(
        "HTTP/1.1 #{status}\r\n" +
        "#{header_str}\r\n")
      @socket.flush()
      @handshaked = true
    end
    
    def send(data)
      if !@handshaked
        raise(WebSocket::Error, "call WebSocket\#handshake first")
      end
      data = data.dup().force_encoding("ASCII-8BIT")
      @socket.write("\x00#{data}\xff")
      @socket.flush()
    end
    
    def receive()
      if !@handshaked
        raise(WebSocket::Error, "call WebSocket\#handshake first")
      end
      packet = @socket.gets("\xff")
      return nil if !packet
      if !(packet =~ /\A\x00(.*)\xff\z/nm)
        raise(WebSocket::Error, "input must start with \\x00 and end with \\xff")
      end
      return $1.force_encoding("UTF-8")
    end
    
    def tcp_socket
      return @socket
    end
    
    def host
      return @header["Host"]
    end
    
    def origin
      return @header["Origin"]
    end
    
    def close()
      @socket.close()
    end

  private
    
    def read_header()
      @header = {}
      @socket.each_line() do |line|
        line = line.chomp()
        break if line.empty?
        if !(line =~ /\A(\S+): (.*)\z/n)
          raise(WebSocket::Error, "invalid request: #{line}")
        end
        @header[$1] = $2
      end
      if @header["Upgrade"] != "WebSocket"
        raise(WebSocket::Error, "invalid Upgrade: " + @header["Upgrade"])
      end
      if @header["Connection"] != "Upgrade"
        raise(WebSocket::Error, "invalid Connection: " + @header["Connection"])
      end
    end
    
end


class WebSocketServer
    
    def initialize(uri, params = {})
      @uri = uri.is_a?(String) ? URI.parse(uri) : uri
      @port = params[:port] || @uri.port || 80
      @accepted_domains = params[:accepted_domains] || [@uri.host]
      if params[:host]
        @tcp_server = TCPServer.open(params[:host], @port)
      else
        @tcp_server = TCPServer.open(@port)
      end
    end
    
    attr_reader(:tcp_server, :uri, :port, :accepted_domains)
    
    def run(&block)
      while true
        Thread.start(accept()) do |s|
          begin
            ws = create_web_socket(s)
            yield(ws) if ws
          rescue => ex
            print_backtrace(ex)
          ensure
            begin
              ws.close() if ws
            rescue
            end
          end
        end
      end
    end
    
    def accept()
      return @tcp_server.accept()
    end
    
    def accepted_origin?(origin)
      domain = URI.parse(origin).host
      return @accepted_domains.any?(){ |d| File.fnmatch(d, domain) }
    end
    
    def create_web_socket(socket)
      ch = socket.getc()
      if ch == ?<
        # This is Flash socket policy file request, not an actual Web Socket connection.
        send_flash_socket_policy_file(socket)
        return nil
      else
        socket.ungetc(ch)
        return WebSocket.new(socket, :server => self)
      end
    end
    
  private
    
    def print_backtrace(ex)
      $stderr.printf("%s: %s (%p)\n", ex.backtrace[0], ex.message, ex.class)
      for s in ex.backtrace[1..-1]
        $stderr.printf("        %s\n", s)
      end
    end
    
    # Handles Flash socket policy file request sent when web-socket-js is used:
    # http://github.com/gimite/web-socket-js/tree/master
    def send_flash_socket_policy_file(socket)
      socket.puts('<?xml version="1.0"?>')
      socket.puts('<!DOCTYPE cross-domain-policy SYSTEM ' +
        '"http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">')
      socket.puts('<cross-domain-policy>')
      for domain in @accepted_domains
        socket.puts("<allow-access-from domain=\"#{domain}\" to-ports=\"#{@port}\"/>")
      end
      socket.puts('</cross-domain-policy>')
      socket.close()
    end

end


if __FILE__ == $0
  Thread.abort_on_exception = true
  case ARGV[0]
    
    when "server"
      server = WebSocketServer.new(
        ARGV[1] || "ws://localhost:10081",
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
    
    when "client"
      client = WebSocket.new(ARGV[1] || "ws://localhost:10081/")
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
    
    else
      $stderr.puts("Usage: ruby web_socket.rb [server|client]")
    
  end
end
