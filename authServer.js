require('dotenv').config()

const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');
app.use(express.json());


let refreshTokens = [];

app.post('/token', (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  })
})

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token!== req.body.token);
  res.sendStatus(204);

})

app.post('/login', (req, res) => {
  //Authenticate User

  const username = req.body.username
  const user = { name: username };

  const accessToken = generateAccessToken(user);
  //userの秘密鍵を使用して署名し、リフレッシュトークンの生成
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  //アクセストークンとリフレッシュトークンをJSON形式で渡す
  //有効期限が切れたらリフレッシュトークンを使用して新しいアクセストークンを取得できるようになる
  res.json({ accessToken: accessToken, refreshToken: refreshToken });

})

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
}



app.listen(4000);