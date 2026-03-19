FROM node:20-slim

# Install system dependencies for Puppeteer + tshark
RUN apt-get update && apt-get install -y \
    chromium \
    chromium-driver \
    tshark \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Allow tshark non-root capture
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark 2>/dev/null || true

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --production

# Copy source
COPY . .

# Create captures directory
RUN mkdir -p /app/captures

# Set Puppeteer to use system Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

EXPOSE 5000

CMD ["node", "index.js"]
