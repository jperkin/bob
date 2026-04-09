--
-- Read pkgpaths from a file, one per line.  Blank lines and comments
-- starting with # are ignored.  Inline comments are supported.
--
function read_pkgpaths(file)
    local paths = {}
    for line in io.lines(file) do
        local path = line:match("^%s*([^#%s]+)")
        if path and path:match("^[^/]+/[^/]+$") then
            table.insert(paths, path)
        end
    end
    return paths
end

--
-- scriptenv(run, env) bundles a shell script body with the environment
-- variables that should be set when it runs.  Intended for use inside
-- a function wrapping a script-typed config field, so the env values
-- can reference other config sections without caring about declaration
-- order.  The script body is plain shell.  Bob sets the env vars on
-- the child process (or prepends them as a prelude over ssh) before
-- executing.
--
function scriptenv(run, env)
    return { run = run, env = env or {} }
end

--
-- dedent(s) strips the common leading whitespace from a multi-line
-- string.  Intended for use with Lua long strings so that script
-- bodies can be indented to match the surrounding config without
-- the indentation ending up in the script itself.
--
-- Algorithm follows Rust's indoc crate: finds the minimum indent
-- (leading spaces/tabs before the first non-whitespace character)
-- across all non-empty lines, then strips exactly that many
-- characters from the start of each line.  Empty lines and
-- whitespace-only lines are excluded from the minimum calculation
-- and become empty lines in the output.  A leading newline (from
-- the [[ delimiter) is stripped, as is trailing whitespace.
--
function dedent(s)
    if s:sub(1, 1) == "\n" then
        s = s:sub(2)
    end
    local min_indent
    for line in s:gmatch("[^\n]+") do
        local indent = line:match("^([ \t]*)[^ \t]")
        if indent and (not min_indent or #indent < min_indent) then
            min_indent = #indent
        end
    end
    if not min_indent or min_indent == 0 then
        return (s:gsub("%s+$", ""))
    end
    local result = {}
    for line in (s .. "\n"):gmatch("(.-)\n") do
        if #line >= min_indent then
            result[#result + 1] = line:sub(min_indent + 1)
        else
            result[#result + 1] = ""
        end
    end
    return (table.concat(result, "\n"):gsub("%s+$", ""))
end
