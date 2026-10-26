# Troubleshooting

If it does not look like that:

| Symptom | Fix |
|---|---|
| Only generic "unknown" edges, no operations table | Docker is not running or the `reconics-zeek` image is missing. Start Docker Desktop, run the install script, upload again. |
| Engines screen shows tools as "not installed" | The `reconics-tools` image is missing, or Docker was not running when the capture ran. |
| `advisory index signature INVALID` | `keys/index-signing.pub` does not match the signed `data/index.json`. `git pull`, or run `java -jar target/reconnics-ng.jar verify --index data/index.json --pubkey keys/index-signing.pub`. |
| Old UI after pulling new code | Re-run step 1 and restart `serve`. The UI is packaged inside the jar. |
| Port 8088 already in use | Stop the old console first (the new one cannot start on the same port). |

No Docker? The console still works with the built-in decoders only (`-Dreconics.engine=NATIVE` forces this): you get the graph and
message kinds, but no operations table and none of the extra engines.
