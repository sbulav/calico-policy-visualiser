# syntax=docker/dockerfile:1

ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginx:1.27-alpine

FROM ${NODE_IMAGE} AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

FROM ${NGINX_IMAGE} AS runtime

ARG VERSION=dev
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Calico Policy Visualiser" \
      org.opencontainers.image.description="Client-side Calico and Kubernetes NetworkPolicy visualizer" \
      org.opencontainers.image.source="https://github.com/sbulav/calico-policy-visualiser" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache curl \
    && adduser -D -u 1000 appuser

COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html

RUN chown -R appuser:appuser \
      /usr/share/nginx/html \
      /var/cache/nginx \
      /var/run \
      /var/log/nginx \
      /tmp

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
