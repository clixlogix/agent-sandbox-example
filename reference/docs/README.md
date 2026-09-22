# Reference material

Whatever the agent is allowed to consult, and nothing it is allowed to change.

This directory is copied into the template at `/srv/reference/docs`, root owned
and mode 0555, which is what `search_documentation` greps. It sits outside
`/workspace` on purpose: the agent owns the workspace and can unlink anything
inside it whatever mode a subdirectory carries, so read only means a path the
agent does not own.

Replace this file with the actual runbooks, API docs, or source the agent needs.
