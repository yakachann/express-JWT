require('dotenv').config()

const express = require('express');
const app = express();

const jwt = require('jsonwebtoken');
app.use(express.json());

const posts = [
  {
    username: 'Kyle',
    title: 'Post 1'
  }
  , {
    username: 'Jim',
    title: 'Post 2'
  }
]

//ミドルウェアauthenticateToken関数を実行して検証を行う
app.get('/posts', authenticateToken, (req, res) => {
  res.json(posts.filter(post => post.username === req.user.name));
})

app.post('/login', (req, res) => {
  //Authenticate User

  const username = req.body.username
  const user = { name: username };

  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  res.json({ accessToken: accessToken });

})

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  //ヘッダーの中では「BEARER TOKEN」のようにスペースがあり、今回はTOKENを取得したいので配列の1番目を指定
  const token = authHeader && authHeader.split(' ')[1];
  //tokenがnullだったらアクセス権を与えない
  if (token == null) return res.sendStatus(401);

  //JWTトークンが有効かどうかを秘密鍵を使って検証する
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    //トークンをもっているが有効ではない
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  })

}

app.listen(3000);