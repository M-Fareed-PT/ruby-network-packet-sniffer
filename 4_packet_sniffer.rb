# 4_packet_sniffer.rb
# Usage:
#   ruby 4_packet_sniffer.rb
# Then follow prompts to select interface and capture duration or ctrl+c to stop.
require 'pcaprub'
require 'ipaddr'
require 'time'

pkt_log = File.open("packets_log.txt", "a")
devs = Pcap.lookupdevs rescue nil

if devs.nil? || devs.empty?
  puts "No capture devices found. Ensure Npcap/WinPcap is installed and run as Administrator."
  exit 1
end

puts "Available devices:"
devs.each_with_index do |d, i|
  puts "[#{i}] #{d.name} - #{d.description}"
end
print "Select device index: "
idx = STDIN.gets.to_i
dev = devs[idx]
puts "Selected: #{dev.name}"

print "Enter capture filter (e.g., 'tcp' or '' for none): "
filter = STDIN.gets.chomp
print "Enter max packets to capture (0 = unlimited): "
max_pkts = STDIN.gets.to_i

cap = Pcap::Capture.open_live(dev.name, 65535, true, 1_000)
cap.setfilter(filter) unless filter.nil? || filter.strip.empty?

suspicious_patterns = [
  /Authorization:\s*Basic/i,
  /password=([^&\s]+)/i,
  /passwd=/i,
  /user=.*&pass=/i,
  /login=.*password=/i
]

count = 0
puts "Starting capture... (Ctrl+C to stop)"
cap.loop(max_pkts == 0 ? -1 : max_pkts) do |pkt|
  count += 1
  ts = Time.now.iso8601
  eth = Pcap::Ethernet.new(pkt)
  # attempt to parse IPv4 and TCP/UDP
  info = []
  begin
    ip = eth.ip
    src = ip.src
    dst = ip.dst
    proto = ip.protocol
    info << "#{src} -> #{dst} proto=#{proto}"
    if ip.respond_to?(:tcp) && ip.tcp?
      tcp = ip.tcp
      sport = tcp.sport
      dport = tcp.dport
      payload = tcp.payload.to_s
      info << "TCP #{sport}->#{dport} len=#{payload.length}"
      suspicious_patterns.each do |pat|
        if payload =~ pat
          puts "[#{ts}] SUSPICIOUS: #{src}:#{sport} -> #{dst}:#{dport} matched #{pat.inspect}"
          pkt_log.puts("#{ts} SUSPICIOUS #{src}:#{sport} -> #{dst}:#{dport} pattern=#{pat.inspect}")
          pkt_log.puts(payload[0,1000])
        end
      end
    elsif ip.udp?
      udp = ip.udp
      info << "UDP #{udp.sport}->#{udp.dport}"
    end
  rescue => e
    # best-effort parsing
  end
  puts "[#{ts}] pkt##{count} #{info.join(' | ')}"
end

pkt_log.close
