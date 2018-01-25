const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const bodyParser = require('body-parser');
const request = require('request-promise');
var session = require('express-session');

app.use(session({
    secret: 'keyboard cat secret session secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');

const apiKey = "59524d06791a9bf0697d7c49eb9168c1";
const apiSecret = "1c13104abbbdb38c04bef9916fa16792";

const scopes = 'read_products,write_content';
const forwardingAddress = "https://3149145c.ngrok.io"; // Replace this with your HTTPS Forwarding address

let shopAccessToken;
let currentShop;

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.get('/redirect', (req, res) => {
    res.render('redirect');
});

app.post('/redirect/new', (req, res) => {
    const path = req.body.path;
    const target = req.body.target;


    if (req.session.accessToken) {
        const shopRequestUrl = 'https://' + req.session.shop + '/admin/shop.json';
        const shopRequestHeaders = {
            'X-Shopify-Access-Token': req.session.accessToken,
        };
        request.get(shopRequestUrl, { headers: shopRequestHeaders })
            .then((shopResponse) => {
                var options = {
                    method: 'POST',
                    uri: "https://" + shop + "/admin/redirects.json",
                    headers: shopRequestHeaders,
                    body: {
                        redirect: {
                            path: path,
                            target: target
                        }
                    },
                    json: true // Automatically stringifies the body to JSON
                };
                request.post(options)
                    .then((data) => {
                        res.end(data);
                    })
                    .catch((error) => { console.log(error) });
            })
            .catch((error) => {
                console.log(error)
                res.status(error.statusCode).send(error.error.error_description);
            });
    }
    else {
        res.end("No Access Token");
    }

});

app.listen(3000, () => {
    console.log('Example app listening on port 3000!');
});

app.get('/shopify', (req, res) => {
    const shop = req.query.shop;
    if (shop) {
        const state = nonce();
        const redirectUri = forwardingAddress + '/shopify/callback';
        const installUrl = 'https://' + shop +
            '/admin/oauth/authorize?client_id=' + apiKey +
            '&scope=' + scopes +
            '&state=' + state +
            '&redirect_uri=' + redirectUri;

        res.cookie('state', state);
        res.redirect(installUrl);
    } else {
        return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
    }
});

app.get('/shopify/callback', (req, res) => {
    const { shop, hmac, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if (state !== stateCookie) {
        return res.status(403).send('Request origin cannot be verified');
    }

    if (shop && hmac && code) {
        const map = Object.assign({}, req.query);
        delete map['signature'];
        delete map['hmac'];
        const message = querystring.stringify(map);
        const generatedHash = crypto
            .createHmac('sha256', apiSecret)
            .update(message)
            .digest('hex');

        if (generatedHash !== hmac) {
            return res.status(400).send('HMAC validation failed');
        }

        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code,
        };

        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token;
                shopAccessToken = accessToken;
                currentShop = shop;

                const shopRequestUrl = 'https://' + shop + '/admin/shop.json';
                const shopRequestHeaders = {
                    'X-Shopify-Access-Token': accessToken,
                };

                req.session.accessToken = accessToken;
                req.session.shop = shop;

            })
            .catch((error) => {
                res.status(error.statusCode).send(error.error.error_description);
            });
    } else {
        res.status(400).send('Required parameters missing');
    }
});
