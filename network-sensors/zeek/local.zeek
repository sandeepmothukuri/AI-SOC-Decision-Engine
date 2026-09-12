# Network-sensor policy for the SOC lab.
# JSON output is enabled by the deployment command so conn.log, dns.log,
# http.log, ssl.log, files.log and weird.log can be consumed by a pipeline.
@load policy/tuning/json-logs

redef LogAscii::logdir = "/logs";
