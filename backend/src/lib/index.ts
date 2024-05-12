import { cors } from "@elysiajs/cors";
import { randomBytes } from "crypto";
import { Elysia, error, t } from "elysia";
import { Argon2id } from "oslo/password";
import { db, lucia } from "./auth.js";

const origin = [
  /http:\/\/localhost:*/,
  /.*\.anish-karthik\.site$/,
  /.*\.anish-karthik\.vercel\.app$/,
];

const authCookie = new Elysia({ name: "authCookie" }).guard((app) =>
  app
    .derive(async (c) => {
      const auth = c.headers["authorization"];
      console.log("authCookie");
      const sessionId = lucia.readSessionCookie(c.headers.cookie ?? "");
      console.log(sessionId);
      if (!sessionId) {
        console.log("no session id");

        return {
          session: null,
          user: null,
          bearer: auth?.startsWith("Bearer ") ? auth.slice(7) : null,
        };
      }

      const { session, user } = await lucia.validateSession(sessionId);
      console.log(session);
      console.log(user);
      if (session && session.fresh) {
        console.log("fresh session");
        c.set.headers["set-cookie"] = lucia
          .createSessionCookie(session.id)
          .serialize();
      }

      if (!session) {
        c.set.headers["set-cookie"] = lucia
          .createBlankSessionCookie()
          .serialize();
      }

      return {
        session,
        user,
        bearer: auth?.startsWith("Bearer ") ? auth.slice(7) : null,
      };
    })
    .post("/logout", async (c) => {
      console.log("logout");
      console.log(c.session, c.user);
      try {
        if (!c.session) {
          return error(401, { message: "Unauthenticated" });
        }
        await lucia.invalidateSession(c.session.id);
        c.set.headers["set-cookie"] = lucia
          .createBlankSessionCookie()
          .serialize();
        return { message: "Logged out" };
      } catch (err: any) {
        console.log(err.message);
        return error(500, { message: "Internal server error" });
      }
    })
    .get("/profile", async (c) => {
      console.log("profile");
      console.log(c.user);
      try {
        if (!c.user) {
          return error(401, { message: "Unauthenticated" });
        }
        return c.user;
      } catch (error: any) {
        console.log(error.message);
        return error(500, { message: "Internal server error" });
      }
    }),
);

const app = new Elysia()
  .use(authCookie)
  .use(
    cors({
      origin,
      maxAge: 600,
      credentials: true,
      allowedHeaders: [
        "*",
        "Authorization",
        "Accept",
        "Content-Type",
        "Origin",
        "set-cookie",
        "Set-Cookie",
        "csrftoken",
      ],
      methods: ["GET", "POST", "OPTIONS"],
    }),
  )
  .get("/", () => "Landing")
  .get("/ping", () => "pong")
  .guard(
    {
      body: t.Object({
        username: t.String(),
        password: t.String(),
      }),
      cookie: t.Object({
        test: t.String(),
      }),
    },
    (app) =>
      app

        .post("/signup", async (c) => {
          console.log("signup");
          try {
            const body = c.body;

            const { username, password } = body;
            console.log(username, password);
            if (!username || !password) {
              return error(400, "Invalid username or password");
            }
            if (await db.user.findUnique({ where: { username } })) {
              console.log("Username already exists");
              return error(400, "Username already exists");
            }
            const hashedPassword = await new Argon2id().hash(password);
            const user =
              (await db.user.findUnique({ where: { username } })) ||
              (await db.user.create({
                data: {
                  username,
                  password: hashedPassword,
                },
              }));
            console.log(user);
            const sessionId = randomBytes(12).toString("hex");
            const session = await lucia.createSession(
              user.id,
              {},
              {
                sessionId,
              },
            );
            console.log(session);
            c.cookie.test.value = "testing";
            const token = lucia.createSessionCookie(session.id);
            console.log(token);
            c.set.headers["set-cookie"] = token.serialize();
            c.set.status = 200;
            console.log(c.headers);
            return { session: session.id, user: user.id };
          } catch (error: any) {
            console.log(error.message);
            return c.error(500, { message: "Internal server error" });
          }
        })
        .post("/login", async (c) => {
          try {
            const { username, password } = c.body;
            console.log(username, password);
            if (!username || !password) {
              return error(400, "Invalid username or password");
            }
            const user = await db.user.findUnique({
              where: {
                username,
              },
            });

            if (!user) {
              return error(401, "Invalid username or password");
            }
            const isValidPassword = await new Argon2id().verify(
              user.password,
              password,
            );
            if (isValidPassword) {
              const sessionId = randomBytes(12).toString("hex");
              const session = await lucia.createSession(
                user.id,
                {},
                { sessionId },
              );
              const token = lucia.createSessionCookie(session.id);
              c.set.headers["set-cookie"] = token.serialize();
              return { session: session.id, user: user.id };
            } else {
              return error(401, "Invalid username or password");
            }
          } catch (error: any) {
            console.log(error.message);
            return error(500, "Internal server error");
          }
        }),
  )

  .listen(3000);
console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
export type App = typeof app;
