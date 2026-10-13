# The webhook's own log format is the default `--logging-format`

cert-manager's webhook framework logs through klog, set up by component-base, whose `-v` verbosity and `text`/`json` formats know nothing of a `--log-level`. So that `--log-level` applies to the framework's lines as well as the webhook's, the webhook registers its own component-base log format, `dnsgate`, which writes JSON lines at `--log-level` and above, and makes it the default `--logging-format`; wrapping or replacing the framework's logging setup was rejected as reaching into code the webhook does not own.

## Consequences

- `--log-level debug` sets klog's `-v` to 4 unless `-v` is given, as klog drops `V(n)` lines before any log format sees them.
- With `--logging-format=text` or `json`, klog's own format writes every line, and `--log-level` only raises the verbosity for `debug`.
- klog hands its warnings to a log format as info lines, so `--log-level warn` filters only the solver's own warnings.
