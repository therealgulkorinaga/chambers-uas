FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        gstreamer1.0-tools \
        gstreamer1.0-plugins-good \
        v4l-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY bridge.sh ./bridge.sh
RUN chmod +x ./bridge.sh

ENTRYPOINT ["./bridge.sh"]
