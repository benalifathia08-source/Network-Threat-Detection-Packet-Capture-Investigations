# Figures

| File | What it shows | How it is made |
|---|---|---|
| `case2-beacon.svg` | The case 2 backdoor on one time axis: the 10-second HTTP beacon (empty replies, tasks, results, the 4.4 MB upload), the 16-second TLS beacon, the dead fallback names, and the refused attempts after the user logged on again | `scripts/make_figures.py` from the case 2 Zeek logs (below) |

The figure uses roles as labels, never domain names, so the image holds no indicators.

To rebuild it, export the data on the tools VM into a file outside the repo (it contains domain names), then run the generator on the laptop:

```bash
cd /var/log/nsm/latest/case-2/zeek
{ jq -r 'select(.uri // "" | test("&[0-9a-f]{64}")) | [.ts, (.status_code|tostring), .method, (.request_body_len|tostring), .host] | @tsv' http.log
  echo "---TLS"; jq -r 'select((.server_name//"")|test("winrun2915|logincrypt8338|opscast3707")) | .ts' ssl.log
  echo "---NX";  jq -r 'select(.rcode_name=="NXDOMAIN" and (.query//""|test("globalcert8618|hostjob3862|opsbox8097"))) | .ts' dns.log
} > ~/case2_beacon.tsv
```

```bash
python -I scripts/make_figures.py case2_beacon.tsv docs/figures/case2-beacon.svg
```
