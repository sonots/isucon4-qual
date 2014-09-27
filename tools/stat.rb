require 'uri'
stats = {}
STDIN.readlines.each do |line|
  uri, reqtime = line.split("\t")
  path = uri.split('?').first
  reqtime = reqtime.to_f
  stat = stats[path] ||= { :count => 0, :sum => 0, :min => 0, :max => 0}
  stat[:sum] += reqtime
  stat[:max] = [stat[:max], reqtime].max
  stat[:min] = [stat[:min], reqtime].min
  stat[:count] += 1
end

stats.each do |path, val|
  val[:mean] = val[:sum] / val[:count].to_f
  out = { :path => path }.merge(val)
  puts out.map {|key, v| "#{key}:#{v}" }.join("\t")
end

