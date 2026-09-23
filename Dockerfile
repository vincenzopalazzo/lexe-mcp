# Static MCP server. Outer TLS uses the embedded Lexe CA, so the
# runtime image does not need a system trust store.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod server.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/lexe-mcp .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lexe-mcp /lexe-mcp
USER nonroot:nonroot
ENV PORT=8010 HOST=0.0.0.0
EXPOSE 8010
ENTRYPOINT ["/lexe-mcp"]
