require('dotenv').config()

const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');
app.use(express.json());

//有効なリフレッシュトークンの配列を生成
let refreshTokens = [];

app.post('/token', (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  //有効なリフレッシュトークン配列に含まれていなければ、今回のrefreshTokenは無効
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  //JWTトークンを秘密鍵を使用して検証する
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    //検証中にエラーが発生した場合、403=アクセス拒否
    if (err) return res.sendStatus(403);
    //正常に処理が成功した場合、JWTアクセストークンを発行（今回は名前を元に発行）
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  })
})

app.delete('/logout', (req, res) => {
  //配列要素からtokenが一致しないものだけを残す、つまり指定されたtokenを配列から削除
  refreshTokens = refreshTokens.filter(token => token!== req.body.token);
  //成功したときに204を返す（レスポンスにデータがないことを示す）
  res.sendStatus(204);

})

app.post('/login', (req, res) => {
  //Authenticate User

  const username = req.body.username
  const user = { name: username };

  const accessToken = generateAccessToken(user);
  //user情報をもとに秘密鍵を使ってJWT(証明書）を発行
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  //有効なリフレッシュトークンを配列に入れる
  refreshTokens.push(refreshToken);
  //アクセストークンとリフレッシュトークンをJSON形式で渡す
  //有効期限が切れたらリフレッシュトークンを使用して新しいアクセストークンを取得できるようになる
  res.json({ accessToken: accessToken, refreshToken: refreshToken });

})

function generateAccessToken(user) {
  //ユーザーの情報を元に、秘密鍵でJWT（証明書）を発行
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
}



app.listen(4000);