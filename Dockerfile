FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev
COPY index.js oauth.js mailcow.js admin-users.js hash-password.js ./
EXPOSE 3901
CMD ["node", "index.js"]
