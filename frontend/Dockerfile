# Frontend image — builds the Next.js app and serves it in production mode.
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
# Next.js bakes rewrite destinations at build time, so the proxy target to the
# backend must be set here (not just at runtime).
ARG API_PROXY_TARGET=http://backend:8000
ENV NEXT_PUBLIC_API_BASE=$API_PROXY_TARGET
RUN npm run build

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/next.config.js ./next.config.js
EXPOSE 3000
CMD ["npm", "run", "start"]
