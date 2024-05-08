require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require ('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('email-validator');

const app = express();
//Transformar em Json

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    next();
  });


app.use(express.json());

//Models
const User = require('./models/User');

//Rota publica

app.get('/', (req,res) =>{
    res.status(200).json({msg:'Bem vindo'})
})

//Rota privada

app.get('/user/:id',checkToken, async (req,res)=>{
    const id = req.params.id;

    try {
        // Checar se o usuário existe
        const user = await User.findById(id,'-senha');

        if(!user){
            return res.status(404).json({msg:"Usuário não encontrado"});
        }

        // Se o usuário existe, enviar os dados, excluindo a senha
        res.status(200).json(user);
    } catch (error) {
        // Se ocorrer algum erro durante a busca, enviar uma resposta de erro
        console.error("Erro ao buscar usuário:", error);
        res.status(500).json({msg:"Erro ao buscar usuário"});
    }
   
});

function checkToken (req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!' });
    }
    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch (e) {
    console.error("Erro ao verificar o token:", e);
    res.status(400).json({ msg: 'Token inválido!', error: e.message });
    }
}

app.post('/register', async(req,res) => {
    
    const {nome,sobrenome,email,senha} = req.body

    //validações

    if(!nome || !sobrenome || !email || !senha){
        return res.status(422).json({msg:"É obrigatório preencher todos os dados para o login"})
    }

   verificacao = validator.validate(email) 
    if(verificacao == false){
        return res.status(422).json({msg:"Email inválido"})
    }


    //checar se já existe o usuario
    const userExists = await User.findOne({email:email})

    if(userExists){
        return res.status(422).json({msg:"Usuário já existente, coloque outro email"})
    }

    //criar senha
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(senha,salt)

    //criar usuario

    const user = new User({
        nome,
        sobrenome,
        email,
        senha: passwordHash,
    })

    try{
        await user.save()
        res.status(201).json({msg:"Usuário criado com sucesso"})
    }
    catch(erro){
        res.status(500).json({msg:"Erro no servidor,tente novamente mais tarde"})
    }
})

//Login  User

app.post('/login', async (req,res) =>{
    const{email,senha} = req.body
    //validação
    if(!email || !senha){
        return res.status(422).json({msg:"É obrigatório preencher todos os dados para o login"})
    }

    //checar se existe

    const user = await User.findOne({email:email})

    if(!user){
        return res.status(404).json({msg:"Usuário não encontrado"})
    }

    //checar se é a senha correspondente

    const checkPassword = await bcrypt.compare(senha,user.senha)

    if(!checkPassword){
        return res.status(422).json({msg:"Senha inválida"})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,
        },
    secret,
)
    res.status(200).json({msg:"Autenticação realizada com sucesso",token})
    }
    catch(erro){
        res.status(500).json({msg:"Erro no servidor,tente novamente mais tarde"})
    }
})

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.ujde7oz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(() => {
    app.listen(3000)
    console.log('Conectado ao mongoDB')
})
.catch((err) => console.log(err));



