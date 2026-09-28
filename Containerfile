# snout-push's image: one static binary on scratch.
#
#   docker buildx build -f Containerfile --platform linux/arm64 -t snout-push .
#
# The context is the repository root, for its lockfile (in the SnoutData monorepo, the stack
# workspace: `-f push/Containerfile packages/stack`). Scratch, because nothing runs in this
# container but the server: TLS roots are compiled in (webpki-roots), names resolve through the
# resolv.conf the runtime mounts, and there is no shell for anything to be run with.
FROM docker.io/library/rust:1.98.1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p snout-push \
	&& cp target/release/snout-push /snout-push

FROM scratch
COPY --from=build /snout-push /snout-push
USER 1000:1000
EXPOSE 5200 5201
ENTRYPOINT ["/snout-push"]
