FROM nginx:1.25-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy frontend files
COPY index.html /usr/share/nginx/html/index.html

# When running in K8s, the API_BASE is handled by nginx proxy
# For local dev, we inject it via script
RUN sed -i "s#window.__API_BASE__ || 'http://localhost:8080'#window.__API_BASE__ || ''#g" \
    /usr/share/nginx/html/index.html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:80/ || exit 1
