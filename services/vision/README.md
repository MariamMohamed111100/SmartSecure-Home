# vision: AI surveillance (Person 4)

A camera (a video file played on a loop, or a real RTSP stream) goes through YOLOv8n, a face
recognizer and a motion detector. Results are published on `security/alerts/vision` in the shared
event envelope, with an annotated snapshot saved to `/data/snapshots/<event-id>.jpg`.

```
video / RTSP -> FrameSource -> YOLOv8n | faces (YuNet+SFace) | motion | fire model
             -> must appear in 2 frames in a row -> per-type cooldown -> snapshot -> MQTT (qos 1)
```

## Run it (3 steps)

```bash
make vision-models                          # once: downloads the free models (~60 MB), checks SHA-256
cp my_clip.mp4 services/vision/media/videos/demo.mp4     # any clip with people / cars
make up                                     # vision starts looping the clip
make watch T=security/alerts/vision         # alerts appear as the clip plays
```

Snapshots show on the dashboard timeline at `http://localhost:8080/snapshots/<event-id>.jpg`.
No clip yet? The service stays healthy, logs `video ... not found. Idling.` and sends no alerts.

**Known faces:** put photos in `services/vision/media/known_faces/<name>/1.jpg` (or `<name>.jpg`),
restart vision. Matches become `person.detected` with `data.name`; everyone else is `face.unknown`.
These photos are personal data: they are git-ignored, never commit them.

**RTSP demo** (a fake IP camera): put `VISION_SOURCE=rtsp://rtsp:8554/camera` in `.env`, then
`docker compose --profile demo up -d rtsp camera vision`.

## What it publishes

| Event | When | `data` (besides `camera_id`, `latency_ms`) |
|---|---|---|
| `face.unknown` (high) | a face that matches nobody in `known_faces/` | `confidence`, `snapshot` |
| `person.detected` | a person (YOLO), or a known face | `confidence`, `snapshot`, `name` if known |
| `vehicle.detected` | car, motorcycle, bus, truck | `confidence`, `snapshot` |
| `package.detected` | backpack, handbag, suitcase (stand-ins, see limits) | `confidence`, `snapshot` |
| `motion.outdoor` | big change in frame, **outdoor zones only** | `confidence`, `sensor_id`, `snapshot` |
| `fire.detected` / `smoke.detected` (critical) | fire model (or heuristic) fires | `confidence`, `snapshot`, `sensor_id` (smoke) |
| `camera.disconnected` | stream down for 10 s | `camera_id` |

`latency_ms` is the time from capturing the frame to publishing the alert (about 0.2 s on a laptop
CPU in our test). If a person is recognised, the plain `person.detected` for that frame is dropped
so one person does not produce two alerts.

## Settings (environment)

| Variable | Default | Meaning |
|---|---|---|
| `VISION_SOURCE` | `/media/videos/demo.mp4` | file (looped) or `rtsp://...` |
| `CAMERA_ID` / `CAMERA_ZONE` | `cam_entrance` / `entrance` | zone must exist in `config/zones.yaml` |
| `VISION_FPS` | 5 | frames analysed per second |
| `CONFIRM_FRAMES` | 2 | frames in a row before an alert (stops flicker) |
| `MIN_CONFIDENCE` / `FACE_MIN_CONFIDENCE` | 0.45 / 0.8 | detection thresholds |
| `FACE_MATCH_THRESHOLD` | 0.363 | SFace cosine cut-off: raise it to be stricter |
| `COOLDOWN_PERSON` etc. | 10 / 30 / 60 s ... | min seconds between alerts of one type |
| `FIRE_MIN_CONF` | 0.55 | minimum confidence for a `fire.detected` from the model |
| `SMOKE_FROM_MODEL` | false | let the model raise `smoke.detected` (see below: off on purpose) |
| `SMOKE_MIN_CONF` | 0.8 | minimum confidence for model smoke, only used when the above is true |
| `FIRE_IMGSZ` | 640 | input size the fire model was exported with (`imgsz=` at export) |
| `FIRE_HEURISTIC` | false | enable the colour+flicker fire detector (demo-grade) |
| `MAX_SNAPSHOTS` | 500 | oldest snapshots are deleted beyond this |

## Fire and smoke

COCO-trained YOLOv8n cannot see fire. For real fire/smoke, put a YOLOv8 ONNX model in
`models/fire.onnx` and its class names (one per line, containing `fire`/`smoke`) in
`models/fire.names`. Without a model fire detection is OFF (the log says so); `FIRE_HEURISTIC=true`
turns on a colour+flicker guess that **will** give false alarms on orange moving things.

Training one for free (Colab GPU, ~20 minutes, Roboflow Universe "fire" dataset; the resulting classes are `Fire`,
`default`, `smoke` in that id order, and `default` is ignored), then:

```bash
yolo export model=best.pt format=onnx imgsz=800 opset=12      # imgsz = the size you trained at
cp best.onnx services/vision/models/fire.onnx
printf 'Fire\ndefault\nsmoke\n' > services/vision/models/fire.names   # SAME order as model.names
echo 'FIRE_IMGSZ=800' >> .env                                  # and pass it to the vision service
```

**Smoke from the model is OFF by default.** `smoke.detected` scores 100 (siren), and the small
Roboflow model fired at 0.90 on a plain white hallway wall while scoring only 0.35-0.57 on real
smoke in the demo clip. Fire (floor 0.55) separated real flames (0.55-0.66) from orange parcels
(<=0.51) on the same clip, but with a thin margin: retrain with more data before relying on it.
Smoke still reaches the engine from the simulators. Turn it on with `SMOKE_FROM_MODEL=true` once
you have a better model.

Check `model.names` in Python first: the line order of `fire.names` must be the class id order.

## Tests

```bash
pytest services/vision/tests -q        # unit + pipeline + real video/file loop, no models needed
VISION_TEST_IMAGES=<folder with bus.jpg, zidane.jpg> pytest services/vision/tests -q   # + real models
```
(`bus.jpg` and `zidane.jpg` ship inside the `ultralytics` pip package, under `ultralytics/assets/`.)

## Known limits (be honest in the demo)

- **Package** detection uses COCO stand-ins (bags/suitcases): a parcel on a doormat is often missed.
- **Fire/smoke** needs a trained model you provide (above).
- Face recognition is a demo-grade 1:N match against a few photos, not an access-control system:
  masks, side views and low light lower accuracy. Check accuracy on your own clips.
- Tested on CPU with files and mocks. Real RTSP camera, Docker and Mosquitto were not run in the
  development sandbox: run `make up` once and confirm with `make watch`.
- YOLOv8 (Ultralytics) is AGPL-3.0; fine for this project, check the licence before selling.
