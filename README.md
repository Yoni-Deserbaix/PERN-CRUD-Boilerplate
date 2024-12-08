# PERN-CRUD-BOILERPLATE

This project is a Docker boilerplate for a simple CRUD application using the PERN stack. <br/>
The PERN stack consists of PostgreSQL, Express, React (Next.js), and Node.js.

<img width="942" alt="PERN stack schema" src="https://github.com/user-attachments/assets/dc478aa0-6bc3-4237-afd8-332c5d3cfd76">


## Technologies Used 🔪

### Language
- **TypeScript**: A superset of JavaScript that compiles to plain JavaScript.

### Backend
- **Express**: A minimal and flexible Node.js web application framework.
- **MVC**: Model-View-Controller architecture for organizing code.
- **Node.js**: A JavaScript runtime built on Chrome's V8 JavaScript engine.
- **Prisma**: ORM (Object-Relational Mapping) tool to facilitate interaction with PostgreSQL database and generate SQL queries more efficiently.

### Frontend
- **React (Next.js)**: A React framework for building server-side rendered applications.
- **TanStack Query**: A powerful data-fetching library for React.
- **Tailwind CSS**: A utility-first CSS framework for rapid UI development.

### Database
- **PostgreSQL**: Relational database management system used for storing user data, product information, and order details.

### Containerization
- **Docker**: A platform for developing, shipping, and running applications in containers.
  
## Docker Configuration 🐳
### Docker Compose file
```dockerfile
# docker-compose.yaml

version: "3.8"

services:
  frontend:
    container_name: frontend
    build:
      context: ./frontend
      dockerfile: frontend.dockerfile
    ports:
      - "${FRONTEND_PORT}:3000"
    environment:
      - NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
    volumes:
      - ./frontend:/app
      - /app/node_modules
    restart: always
    depends_on:
      - backend

  backend:
    container_name: backend
    image: backend:latest
    build:
      context: ./backend
      dockerfile: backend.dockerfile
    ports:
      - "${BACKEND_PORT}:4000"
    environment:
      - DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}

  db:
    container_name: db
    image: postgres:latest
    restart: always
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    ports:
      - "${DB_PORT}:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata: {}
```
### Backend Dockerfile
``` dockerfile
# backend.dockerfile

FROM node:20

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY prisma ./prisma

RUN npx prisma generate

COPY . .

EXPOSE 4000

CMD ["npm", "run", "dev"]

```
### Frontend Dockerfile
```dockerfile
# frontend.dockerfile

FROM node:18

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

CMD npm run dev
```

## 🤸 Quick Start

To get started with this project, follow these steps:

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd PERN-CRUD-BOILERPLATE
   ```

2. Set up your environment variables:
   Create a `.env` file in the `backend` directory and add your PostgreSQL connection string:

   ```   
    DATABASE_URL=postgresql://example_user:example_password@localhost:5432/example_db?schema=public
   ```

3. Build and run the Docker containers:

   ```bash
   docker-compose up --build
   ```

4. Access the application:

   - Frontend: [http://localhost:3000](http://localhost:3000)
   - Backend API: [http://localhost:4000](http://localhost:4000)
   - DB: [http://localhost:5432](http://localhost:5432) 

5. To create a new migration, run:
   ```bash
   npx prisma migrate dev --name init
   ```



## 🔧 Contributing

[![contributors](https://contrib.rocks/image?repo=yoni-deserbaix/yoni-deserbaix)](https://github.com/Yoni-Deserbaix/Aora/graphs/contributors)

Contributions are what make the open source community such an amazing place to learn, inspire, and
create. Any contributions you make are **greatly appreciated**.

To fix a bug or enhance an existing module, follow these steps:

1. Fork the repo
2. Create a new branch (`git checkout -b improve-feature`)
3. Make the appropriate changes in the files
4. Commit your changes (`git commit -am 'Improve feature'`)
5. Push to the branch (`git push origin improve-feature`)
6. Create a Pull Request 🎉

