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
