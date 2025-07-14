# Use official Node.js image
FROM node:18

# Create app directory
WORKDIR /app

# Copy package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of your application
COPY . .

# Hugging Face Spaces provides a PORT env variable. Your app should listen on it.
ENV PORT=7860

# Expose the port (not strictly required for HF Spaces, but good practice)
EXPOSE $PORT

# Start the app
CMD ["npm", "start"]
