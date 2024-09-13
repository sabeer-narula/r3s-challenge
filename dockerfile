FROM node:14

WORKDIR /usr/encryption

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

CMD ["node", "dist/libs/decryptString.js"]