require('dotenv').config();

// Import dependencies
import express from "express";
import mysql2 from "mysql2";
import bodyParser from "body-parser";
import argon2 from "argon2";
import parseUrl from "url-parse";
import i18n from "i18n";

import {checkUrl} from "./virustotal";
import * as blocklist from "./blocklist";


// Define HTTP port
const PORT: number = parseInt(process.env.PORT) || 3000;

// Configure i18n
i18n.configure({
    locales:['en', 'de'],
    directory: 'src/locales/',
    cookie: "locale",
    queryParameter: "hl",
    objectNotation: true,
    defaultLocale: "de"
});

// Initialize express server object
const app: express.Application = express();

// Use Body parser middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));


// Use i18n middleware
app.use(i18n.init);

app.set("view engine", "pug");
app.set("views", "src/views/");

// Initialize MySQL
const mysql: mysql2.Connection = mysql2.createConnection({
    host: process.env.MYSQL_SERVER,
    user: process.env.MYSQL_USERNAME,
    database: process.env.MYSQL_DATABASE,
    password: process.env.MYSQL_PASSWORD,
    // Use SSL client auth
    /*ssl: {
        // SSL variables are stored Base64 encoded for better compatibility
        key: Buffer.from(process.env.MYSQL_KEY, "base64").toString("ascii"),
        cert: Buffer.from(process.env.MYSQL_CERT, "base64").toString("ascii"),
        ca: Buffer.from(process.env.MYSQL_CA, "base64").toString("ascii")
    }*/
});


app.get("/", (req: express.Request, res: express.Response) => {
    res.render("shorten");
});

function makeSlug(length: number): string {
    let result: string           = '';
    const characters: string       = 'abcdefghijklmnopqrstuvwxyz23456789';
    const charactersLength: number = characters.length;
    for ( var i: number = 0; i < length; i++ ) {
       result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
 }

app.post("/", async (req: express.Request, res: express.Response) => {
    if(req.body.url) {
        let url: string = req.body.url;
        if (!/^https?:\/\//i.test(url)) {
            url = 'http://' + url;
        }
        if(await checkUrl(url)) {
            if(await blocklist.checkUrlShortener(url)) {
                if(await blocklist.checkPornTop1Million(url)) {
                    const slug: string = makeSlug(3);
                    const token: string = makeSlug(128);
                    await mysql.promise().query("INSERT INTO Redirects (slug, target, token, maximumHits) VALUES (?, ?, ?, ?);", [
                        slug,
                        parseUrl(url).href,
                        await argon2.hash(token, {
                            type: argon2.argon2id
                        }),
                        0
                    ]);
                    res.render("shorten", {
                        success: res.__("Success"),
                        url: url,
                        slug: slug,
                        token: token
                    });
                } else {
                    res.render("shorten", {
                        url: url,
                        error: res.__("ErrorPorn")
                    });
                }
            } else {
                res.render("shorten", {
                    url: url,
                    error: res.__("ErrorUrlShortener")
                });
            }
        } else {
            res.render("shorten", {
                url: url,
                error: res.__("ErrorVirustotal")
            });
        }
    } else {
        res.render("shorten", {
            error: res.__("ErrorNoUrl")
        });
    }
});

app.get("/:slug", async (req: express.Request, res: express.Response) => {
    const slug: string = req.params.slug;
    let redirects: any;
    let blackhole: any;
    [redirects, blackhole] = await mysql.promise().query("SELECT * FROM Redirects WHERE slug = ? AND deleted = 0 AND locked = 0;", [
        slug
    ]);
    if(redirects.length == 1) {
        res.redirect(302, redirects[0].target);
    } else {
        res.status(404);
        res.send("404");
    }
});

// Start server
app.listen(PORT, () => {
    // Log what port the server is listening on
    console.log(`Listening on port ${PORT}...`);
})


