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
