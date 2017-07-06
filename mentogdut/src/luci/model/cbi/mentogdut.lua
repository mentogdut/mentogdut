--[[
LuCI - MentoGDUT Configuration Interface
]]--

require("luci.sys")

m = Map("mentogdut", "MentoGDUT", "A third-party client of Dr.COM 5.2.1(p) for gdut.")

s = m:section(TypedSection, "mentogdut", "")
s.addremove = false
s.anonymous = true

enable = s:option(Flag, "enable", "Enable")
enable.default = enable.disabled

server = s:option(Value, "server", "Auth Server", "HEMC 10.0.3.2, others 10.0.3.6")
server:depends("enable", enable.enabled)
server.datatype = "ipaddr"

port = s:option(Value, "port", "Port", "default 61440")
port:depends("enable", enable.enabled)
port.datatype = "port"

pppoe_flag = s:option(Value, "pppoe_flag", "PPPoE Flag", "default 6a")
pppoe_flag:depends("enable", enable.enabled)
pppoe_flag.datatype = "rangelength(2,2)"

keep_alive2_flag = s:option(Value, "keep_alive2_flag", "Keep-Alive2 Flag", "optional, default dc")
keep_alive2_flag:depends("enable", enable.enabled)
keep_alive2_flag.datatype = "rangelength(2,2)"

macaddr = s:option(Value, "macaddr", "MAC Address")
macaddr:depends("enable", enable.enabled)
macaddr.datatype = "macaddr"
macaddr:value("", "don't change (default)")
luci.sys.net.mac_hints(function(mac, name)
	macaddr:value(mac, "%s (%s)" %{ mac, name })
end)

patch = s:option(Flag, "patch", "Apply PPPoE Patch", "whether to patch ppp.sh or not, default yes")
patch:depends("enable", enable.enabled)
patch.default = patch.enabled

logger = s:option(Flag, "logger", "Enable Logger", "redirects all output to /tmp/mentogdut.log, default no")
logger:depends("enable", enable.enabled)
logger.default = logger.disabled

checksum = s:option(ListValue, "checksum", "Encryption")
checksum:depends("enable", enable.enabled)
checksum:value("0","0 Automatic")
checksum:value("1","1 None")
checksum:value("2","2 Enabled")

enabledial = s:option(Flag, "enabledial", "Automatic Configure PPPoE", "not recommended to enable this")
enabledial.default = enabledial.disabled
enabledial:depends("enable",enable.enabled)

ifname = s:option(ListValue, "ifname", "Interface Name", "default eth0.2")
ifname:depends("enabledial", enabledial.enabled)
for k, v in ipairs(luci.sys.net.devices()) do
	ifname:value(v)
end
ifname.default = "eth0.2"

username = s:option(Value, "username", "Username")
username:depends("enabledial", enabledial.enabled)

password = s:option(Value, "password", "Password")
password:depends("enabledial", enabledial.enabled)
password.password = true

refresh = s:option(Flag, "refresh", "Restart Network", "whether to restart network devices or not, default not")
refresh:depends("enable", enable.enabled)
refresh.default = refresh.disabled

local apply = luci.http.formvalue("cbi.apply")
if apply then
	io.popen("/etc/init.d/mentogdut restart")
end

return m
