import express, { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { auth, requiresAuth } from 'express-openid-connect';
import dotenv from 'dotenv';
import pg from 'pg';
import crypto from 'crypto';
import QRCode from 'qrcode';
import { auth as auth2 } from 'express-oauth2-jwt-bearer';


dotenv.config();

const app = express();

app.use(express.json());

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Connected to the database');
  release();
});

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 3000;

const config = {
  authRequired: false,
  idpLogout: true,
  secret: process.env.SECRET,
  baseURL: externalUrl || `http://localhost:${port}`,
  clientID: process.env.CLIENT_ID,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  clientSecret: process.env.CLIENT_SECRET,
  authorizationParams: {
    response_type: 'code',
  },
};

app.use(auth(config));

// Početna stranica
app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM tickets');
    const ticketCount = result.rows[0].count;

    if (req.oidc && req.oidc.isAuthenticated()) {
      res.send(`
        <h1>Logged in. <a href="/logout">Logout</a></h1>
        <p>Number of generated ticekts: ${ticketCount}</p>
        ${generateTicketForm()}
        <img id="qrCodeImage" alt="QR Code" style="display:none; margin-top:20px;"/> 
      `);
    } else {
      res.send(`
        <h1>Logged out. <a href="/login">Login</a> or <a href="/sign-up">Sign Up</a></h1>
        <p>Number of created ticekts: ${ticketCount}</p>
        ${generateTicketForm()}
        <img id="qrCodeImage" alt="QR Code" style="display:none; margin-top:20px;"/> 
      `);
    }
  } catch (err) {
    console.error('Error retrieving ticket count:', err);
    res.status(500).send('Error retrieving ticket count');
  }
});

function generateTicketForm() {
  return `
    <div style="border: 1px solid #000; padding: 20px; width: 300px; margin-top: 20px;">
      <h2>GENERATE TICKET</h2>
      <form id="ticket-form">
        <label for="vatin">OIB:</label><br>
        <input type="text" id="vatin" name="vatin" required><br><br>

        <label for="firstName">First Name:</label><br>
        <input type="text" id="firstName" name="firstName" required><br><br>

        <label for="lastName">Last Name:</label><br>
        <input type="text" id="lastName" name="lastName" required><br><br>

        <button type="button" onclick="generateTicket()">Generate Ticket</button>
      </form>
      <script>
        async function generateTicket() {
          const vatin = document.getElementById('vatin').value;
          const firstName = document.getElementById('firstName').value;
          const lastName = document.getElementById('lastName').value;

          const response = await fetch('/create-ticket', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vatin, firstName, lastName })
          });

          if (!response.ok) {
            const errorResult = await response.json();
            alert(errorResult.error || 'Greška pri stvaranju ulaznice');
            return;
          }

          const result = await response.json();
          if (result.qrCodeImage) {
            document.getElementById('qrCodeImage').src = result.qrCodeImage;
            document.getElementById('qrCodeImage').style.display = 'block';
          } else {
            alert(result.message || 'ERROR');
          }
        }
      </script>
    </div>
  `;
}

app.post('/create-ticket', async (req, res) => {
  try {
    const token = await getM2MToken();
    const checkJwt = auth2({
      audience: `https://${process.env.M2M_AUTH0_DOMAIN}/api/v2/`,  
      issuerBaseURL: `https://${process.env.M2M_AUTH0_DOMAIN}/`,
      tokenSigningAlg: 'HS256',
    });
    app.use(checkJwt);
    
    const { vatin, firstName, lastName } = req.body;

    if (!vatin || !firstName || !lastName) {
      res.status(400).json({ error: 'All fields are required' });
      return;
    }

    if (!/^\d{11}$/.test(vatin)) {
      res.status(400).json({ error: 'OIB must have 11 digits.' });
      return;
    }

    const countResult = await pool.query('SELECT COUNT(*) FROM tickets WHERE vatin = $1', [vatin]);
    const ticketCount = parseInt(countResult.rows[0].count, 10);

    if (ticketCount >= 3) {
      res.status(500).json({ error: 'Maximum of 3 tickets per person.' });
      return;
    }

    const ticketId = crypto.randomUUID();

    const insertQuery = 'INSERT INTO tickets (id, vatin, first_name, last_name, created_at) VALUES ($1, $2, $3, $4, NOW())';
    await pool.query(insertQuery, [ticketId, vatin, firstName, lastName]);

    const ticketUrl = `http://localhost:${port}/ticket/${ticketId}`;
    const qrCodeImage = await QRCode.toDataURL(ticketUrl);

    res.status(201).json({
      message: 'Ticket created',
      ticketUrl,
      qrCodeImage,
    });
  } catch (error) {
    console.error('Error during ticket creation:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function getM2MToken(): Promise<string> {
  const url = `https://${process.env.M2M_AUTH0_DOMAIN}/oauth/token`;

  const data = {
    client_id: process.env.M2M_CLIENT_ID,
    client_secret: process.env.M2M_CLIENT_SECRET,
    audience: `https://${process.env.M2M_AUTH0_DOMAIN}/api/v2/`,
    grant_type: 'client_credentials',
  };

  try {
    const response = await axios.post(url, data);
    return response.data.access_token;
  } catch (error) {
    console.error('Error getting M2M token:', error);
    throw new Error('Failed to obtain M2M token');
  }
}


app.get('/ticket/:id', requiresAuth(), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('SELECT vatin, first_name, last_name, created_at FROM tickets WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Ticket not found' });
      return
    }

    const ticket = result.rows[0];
    const userName = req.oidc.user?.name;

    res.send(`
      <h1>Ticket Details</h1>
      <p><strong>OIB:</strong> ${ticket.vatin}</p>
      <p><strong>First Name:</strong> ${ticket.first_name}</p>
      <p><strong>Last Name:</strong> ${ticket.last_name}</p>
      <p><strong>Created At:</strong> ${new Date(ticket.created_at).toLocaleString()}</p>
      <hr>
      <p>Logged-in user: ${userName}</p>
    `);
  } catch (error) {
    console.error('Error retrieving ticket:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/login', (req, res) => {
  res.oidc.login({
    returnTo: '/',
  });
});


app.get('/sign-up', (req, res) => {
  res.oidc.login({
    returnTo: '/',
    authorizationParams: { screen_hint: 'signup' },
  });
});

if (externalUrl) {
  const hostname = '0.0.0.0'; //ne 127.0.0.1
  app.listen(port, hostname, () => {
  console.log(`Server locally running at http://${hostname}:${port}/ and from
  outside on ${externalUrl}`);
  });
}
else{
  app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
  });
}



//prvikorisnik@mail.com
//Sifra.1!