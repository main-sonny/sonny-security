-- SONNY Security Toolkit | Developer: Sonny
-- Trusted policy code: stdout protocol is header-name<TAB>severity.
-- Extend or override the default Python header rules.
local policy = {
    ["strict-transport-security"] = "high",
    ["content-security-policy"] = "high",
    ["x-content-type-options"] = "medium",
    ["referrer-policy"] = "low",
    ["permissions-policy"] = "low",
    ["cross-origin-opener-policy"] = "medium",
}
local names = {}
for name in pairs(policy) do names[#names + 1] = name end
table.sort(names)
for _, name in ipairs(names) do
    io.write(name, "\t", policy[name], "\n")
end
