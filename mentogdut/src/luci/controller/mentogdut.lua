module("luci.controller.mentogdut", package.seeall)

function index()
	entry({"admin", "services", "mentogdut"}, cbi("mentogdut"), _("MentoGDUT"), 100)
	end
