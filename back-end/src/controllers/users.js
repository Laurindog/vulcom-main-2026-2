import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import argon2 from 'argon2'

const argon2Options = {
  type: argon2.argon2id,
  memoryCost: 66560,
  timeCost: 3,
  parallelism: 4
}

const controller = {}     // Objeto vazio


controller.create = async function(req, res) {
  try {
    const { password, ...userData } = req.body

    if(!password) return res.status(400).end()

    const passwordHash = await argon2.hash(password, argon2Options)

    await prisma.user.create({
      data: {
        ...userData,
        password: passwordHash
      }
    })

    res.status(201).end()
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}


controller.retrieveAll = async function(req, res) {
  try {
    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // a consulta expõe todos os campos dos usuários, incluindo a senha em texto puro (A04).
    const result = await prisma.user.findMany({ omit: { password: true } })

    // HTTP 200: OK (implícito)
    res.send(result)
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveOne = async function(req, res) {
  try {
    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // o ID recebido permite consultar qualquer usuário, incluindo seu campo password.
    const result = await prisma.user.findUnique({
      where: { id: Number(req.params.id) },
      omit: { password: true }
    })

    // Encontrou ~> retorna HTTP 200: OK (implícito)
    if(result) res.send(result)
    // Não encontrou ~> retorna HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}


controller.update = async function(req, res) {
  try {
    const { password, ...userData } = req.body

    const data = { ...userData }

    if(password) {
      data.password = await argon2.hash(password, argon2Options)
    }

    await prisma.user.update({
      where: { id: Number(req.params.id) },
      data
    })

    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      return res.status(404).end()
    }

    console.error(error)
    res.status(500).end()
  }
}


controller.delete = async function(req, res) {
  try {
    await prisma.user.delete({
      where: { id: Number(req.params.id) }
    })

    // Encontrou e excluiu ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      // Não encontrou e não excluiu ~> HTTP 404: Not Found
      res.status(404).end()
    }
    else {
      // Outros tipos de erro
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}

controller.login = async function(req, res) {
  try {

      // Busca o usuário no BD usando o valor dos campos
      // "username" OU "email"
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { username: req.body?.username },
            { email: req.body?.email }
          ]
        }
      })

      // Se o usuário não for encontrado, retorna
      // HTTP 401: Unauthorized
      if(! user) return res.status(401).end()

      // Usuário encontrado, vamos conferir a senha
      // OWASP Top 10:2025 A07 - Falhas de Autenticação:
      // a credencial fixa admin/admin123 ignora a senha cadastrada para esse usuário.
      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // a comparação direta usa a senha armazenada em texto puro, sem hash adaptativo.
     


let passwordIsValid = false

// Verifica se a senha já está armazenada em formato Argon2.
if(user.password?.startsWith('$argon2')) {
  passwordIsValid = await argon2.verify(
    user.password,
    req.body?.password ?? ''
  )
}
else {
  // Compatibilidade temporária com senhas antigas em texto claro.
  passwordIsValid = user.password === req.body?.password

  // Se a senha estiver correta, transforma em hash Argon2id.
  if(passwordIsValid) {
    const passwordHash = await argon2.hash(
      req.body.password,
      argon2Options
    )

    await prisma.user.update({
      where: { id: user.id },
      data: { password: passwordHash }
    })

    user.password = passwordHash
  }
}

// Se a senha estiver incorreta, retorna HTTP 401.
if(!passwordIsValid) return res.status(401).end()




      if(user.password) delete user.password

      // Usuário e senha OK, passamos ao procedimento de gerar o token
      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // removemos a senha antes de gerar o JWT para evitar expor credenciais.
      const token = jwt.sign(
        user,                       // Dados do usuário
        process.env.TOKEN_SECRET,   // Senha para criptografar o token
        { expiresIn: '24h' }        // Prazo de validade do token
      )

      // Formamos o cookie para enviar ao front-end
      res.cookie(process.env.AUTH_COOKIE_NAME, token, {
        httpOnly: true, // O cookie ficará inacessível para o JS no front-end
        secure: true,   // O cookie será criptografado em conexões https
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 100  // 24h
      })

      // Retorna o token e o usuário autenticado com
      // HTTP 200: OK (implícito)
      // A senha não é enviada na resposta ao cliente.
      res.send({token, user})

  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.me = function(req, res) {
  // Retorna as informações do usuário autenticado
  // HTTP 200: OK (implícito)
  res.send(req?.authUser)
}

export default controller