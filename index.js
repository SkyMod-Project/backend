import Fastify from 'fastify';
import FastifyCookie from '@fastify/cookie';
import FastifyView from '@fastify/view';
import ejs from 'ejs';
import * as jose from 'jose';

const fastify = Fastify({
    /* logger: true */
});
fastify.register(FastifyCookie, {});
fastify.register(FastifyView, {
    engine: {
        ejs
    }
});

const cookieOptions = {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    maxAge: 7 * 24 * 3600 * 1000
};

const encodedSecret = new TextEncoder().encode(process.env.SECRET);

fastify.get('/', async (req, res) => {
    res.header('Content-Type', 'text/html');
    return await Bun.file('./index.html').text();
});

fastify.get('/index.css', async (req, res) => {
    res.header('Content-Type', 'text/css');
    return await Bun.file('./index.css').text();
});

fastify.get('/auth', async (req, res) => {
    let data;
    try {
        data = (await jose.jwtVerify(req.cookies.jwt, encodedSecret)).payload;
    } catch {
        data = null;
    }

    if (data != null) {
        /* await res.view('./auth.ejs', {
            name: data.name,
            jwt: req.cookies.jwt
        }); */

        await res.redirect(req.query.redirect);
    } else {
        if (req.query.privateCode) {
            const result = await fetch('https://auth.itinerary.eu.org/api/auth/verifyToken?privateCode=' + req.query.privateCode);
            const json = await result.json();
    
            if (json.valid) {
                const token = await new jose.SignJWT({ name: json.username })
                    .setProtectedHeader({ alg: 'HS256', typ: 'jwt' })
                    .setExpirationTime('7 days')
                    .sign(encodedSecret);
                res.cookie('jwt', token, cookieOptions);
                res.cookie('name', json.username, {
                    path: '/',
                    sameSite: 'lax',
                    secure: true,
                    maxAge: 7 * 24 * 3600 * 1000
                });
                /* await res.view('./auth.ejs', { name: json.username, jwt: token }); */
                res.redirect(req.query.redirect);
            } else {
                res.header('Content-Type', 'text/html');
                return await Bun.file('./failed.html').text();
            }
        } else {
            await res.redirect('https://auth.itinerary.eu.org/auth/?redirect=' + Buffer.from('http://localhost:3000/auth?redirect=' + req.query.redirect).toString('base64') + '&name=SkyMod');
        }
    }
});

fastify.get('/logout', (req, res) => {
    res.clearCookie('jwt', cookieOptions);
    res.clearCookie('name', {
        path: '/',
        sameSite: 'lax',
        secure: true,
        maxAge: 7 * 24 * 3600 * 1000
    });
    res.redirect(req.query.redirect);
});

try {
    await fastify.listen({ port: 3000 })
} catch (err) {
    fastify.log.error(err)
    process.exit(1)
}