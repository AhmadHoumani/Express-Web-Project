var express = require("express"),
    mongoose = require("mongoose"),
    bodyParser = require("body-parser"),
    methodOverride = require("method-override"),
    expressSanitizer = require("express-sanitizer"),
    flash = require("connect-flash"),
    session = require("express-session"),
    app = express(),
    moment = require("moment"),
    crypto = require('crypto'),
    nodemailer = require('nodemailer'),
    Bcrypt = require("bcryptjs");

const { check, validationResult } = require('express-validator');

mongoose.connect("mongodb://localhost/restful_shoe_app",{useNewUrlParser:true,useUnifiedTopology:true});
app.set("view engine","ejs");
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
app.use(bodyParser.urlencoded({extended:true}));
app.use(expressSanitizer());
app.use(express.static("public"));
app.use(methodOverride("_method"));
app.use(flash());
app.use(express.json());

app.use(session({
    secret: 'This is a black bear',
    resave: false,
    saveUninitialized: false
}));

app.use(function(req,res,next){
    currentUserId = req.session.userId;
    currentUser = req.session.username;
    res.locals.error = req.flash("error");
    res.locals.success = req.flash("success");
    next();
});


var shoeSchema = new mongoose.Schema({
    title:String,
    image:String,
    body:String,
    author:{
        id:{
            type:mongoose.Schema.Types.ObjectId,
            ref:"User"
        },
        name:String
    },
    created:{type:String,default:moment().format('MMMM Do YYYY, hh:mm A')}
});

var shoe = mongoose.model("shoe",shoeSchema);

var userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    isVerified: { type: Boolean, default: false },
    password: String,resetPasstoken:String,
    resetPasstokenExpire:Date
  });

var User = mongoose.model("User",userSchema);

const tokenSchema = new mongoose.Schema({ 
    _userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
    token: { type: String, required: true },
    expireAt: { type: Date, default: Date.now, index: { expires: 86400000 } }
});

var Token = mongoose.model("Token",tokenSchema);

app.get("/",function(req,res){
    res.redirect("/shoes");
});

app.get("/login",function(req,res){
    res.render("login.ejs");
});

app.post("/login",function(req,res,next){
    User.findOne({ email: req.body.email }, function(err, user) {
        if (!user){
            req.flash('error','The email address ' + req.body.email + ' is not associated with any account. Double-check your email address and try again.');
            res.redirect('/login');
        }
        else if(!Bcrypt.compareSync(req.body.password, user.password)){
            req.flash('error','Wrong Password!');
            res.redirect('/login');
        }
        else if (!user.isVerified){
            req.flash('error','Your Email has not been verified. Please click on resend');
            res.redirect('/login');
        } else{
            req.session.loggedIn = true;
            req.session.userId = user._id;
            req.session.username = user.name;
            res.redirect("/shoes");
        }
    });

});

app.get("/register",function(req,res){
    res.render("register");
})

app.post('/register',function(req,res,next){
  User.findOne({ email: req.body.email }, function (err, user) {
    if (user) {
        req.flash('error','The email address you have entered is already associated with another account.');
        res.redirect('/register');
    }
    else{ 
        req.body.password = Bcrypt.hashSync(req.body.password, 10);
        user = new User({ name: req.body.name, email: req.body.email, password: req.body.password,resetPasstoken: null,resetPasstokenExpire: null });
        user.save(function (err) {
            if (err) { return console.log(err); }

            var token = new Token({ _userId: user._id, token: crypto.randomBytes(16).toString('hex') });
            token.save(function (err) {
                if (err) {return console.log(err); }

                // Send the email
                var transporter = nodemailer.createTransport({ service: 'Sendgrid', auth: { user: 'apikey', pass: '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' } });
                var mailOptions = { from: 'Ahmad_houmani@live.com', to: user.email, subject: 'Account Verification Token', text: 'Hello '+ req.body.name +',\n\n' + 'Please verify your account by clicking the link: \nhttp:\/\/' + req.headers.host + '\/confirmation\/' + user.email + '\/' + token.token + '\n\nThank You!\n' };
                transporter.sendMail(mailOptions, function (err) {
                    if (err) { 
                        req.flash('error','Technical Issue!, Please click on resend for verify your Email.');
                        return res.redirect('/shoes');
                     }
                    req.flash('success','A verification email has been sent to ' + user.email + '. It will be expire after one day. If you not get verification Email click on resend token.')
                    return res.redirect('/login');
                });
            });
        });
    }
    
  });

});

app.get('/confirmation/:email/:token',function(req,res,next){
    Token.findOne({ token: req.params.token }, function (err, token) {
        if (!token){
            req.flash('error','We were unable to find a valid token. Your token may have expired. Please click on resend for verify your Email.');
            res.redirect('/login');
        }else{
            User.findOne({ _id: token._userId, email: req.params.email }, function (err, user) {
                if (!user){
                    req.flash('error','We were unable to find a user for this verification. Please SignUp!');
                    res.redirect('/register');
                } 
                else if (user.isVerified){
                    req.flash('success','This user has already been verified. Please Login');
                    res.redirect('/login');
                }
                else{
                    user.isVerified = true;
                    user.save(function (err) {
                        if (err) { return console.log(err); }
                        req.flash('success','The account has been verified. Please Login.')
                        return res.redirect("/login");
                    });
                }
            });
        }
        
    });
});

app.get('/resendToken',function(req,res){
    res.render("resendToken");
});

app.post('/resendToken',function(req,res,next) {

    User.findOne({ email: req.body.email }, function (err, user) {
        if (!user){
            req.flash('error','We were unable to find a user with that email. Make sure your Email is correct!');
            res.redirect('/login');
        }
        else if (user.isVerified){
            req.flash('error','This account has already been verified. Please log in.');
            res.redirect('/login');
        } 
        else{
            var token = new Token({ _userId: user._id, token: crypto.randomBytes(16).toString('hex') });
            token.save(function (err) {
                if (err) { return console.log(err); }
    
                // Send the email
                    var transporter = nodemailer.createTransport({ service: 'Sendgrid', auth: { user: 'apikey', pass: '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' } });
                    var mailOptions = { from: 'ahmad_houmani@live.com', to: user.email, subject: 'Account Verification Token', text: 'Hello '+ user.name +',\n\n' + 'Please verify your account by clicking the link: \nhttp:\/\/' + req.headers.host + '\/confirmation\/' + user.email + '\/' + token.token + '\n\nThank You!\n' };
                    transporter.sendMail(mailOptions, function (err) {
                        if (err) { 
                            req.flash('error','Technical Issue!, Please click on resend verify Email.');
                            return res.redirect('/shoes');
                         }
                        req.flash('success','A verification email has been sent to ' + user.email + '. It will be expire after one day. If you not get verification Email click on resend token.')
                        return res.redirect('/login');
                    });
            });
        }
    });
});
//Forgot Password
app.get('/forgotpassword',function(req,res){
    res.render("forgotpassword");
});
app.post('/forgotpassword',function(req,res,next) {

    User.findOne({ email: req.body.email }, function (err, user) {
        if (!user){
            req.flash('error','We were unable to find a user with that email. Make sure your Email is correct!');
            res.redirect('/login');
        }
        else{
            var token = new Token({ _userId: user._id, token: crypto.randomBytes(16).toString('hex') });
            token.save(function (err) {
                if (err) { return console.log(err); }
    
                // Send the email
                    var transporter = nodemailer.createTransport({ service: 'Sendgrid', auth: { user: 'apikey', pass: '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' } });
                    var mailOptions = { from: 'ahmad_houmani@live.com', to: user.email, subject: 'Account Verification Token', text: 'Hello '+ user.name +',\n\n' + 'Please reset your account password by clicking the link: \nhttp:\/\/' + req.headers.host + '\/reset\/' + user.email + '\/' + token.token + '\n\nThank You!\n' };
                    transporter.sendMail(mailOptions, function (err) {
                        if (err) { 
                            req.flash('error','Technical Issue!, Please click on resend verify Email.');
                            return res.redirect('/shoes');
                         }
                         user.resetPasstoken=token.token;
                         user.resetPasstokenExpire=Date.now()+86400000;
                         user.save(function (err) {
                            if (err) { return console.log(err); }
                            req.flash('success','A reset email has been sent to ' + user.email + '. It will be expire after one day. If you did not get an Email click on Forgot Password Again!.')
                            return res.redirect('/login');
                        });

                    });
            });
        }
    });
});
//Reset Password
app.get('/reset/:email/:token',function(req,res){

    User.findOne({email:req.params.email,resetPasstoken:req.params.token,
        resetPasstokenExpire:{$gt:Date.now()}},function(err,user){
        if(!user){
            req.flash('error','Password reset token expired or expired.')
            return res.redirect('/forgotpassword');
        }
        res.render('reset',{email:req.params.email,resetPasstoken:req.params.token});
    })
});

app.post('/reset/:email/:token',function(req,res){
    User.findOne({resetPasstoken:req.params.token,resetPasstokenExpire:{$gt:Date.now()}},function(err,user){

    if(!user){
        req.flash('error','Password reset token ivlaid or expired.')
        return res.redirect('/forgotpassword');
    }
    if(req.body.password===req.body.confirm){
        req.body.password = Bcrypt.hashSync(req.body.password, 10);
        user.password=req.body.password
        user.resetPasstoken=null;
        user.resetPasstokenExpire=null;
        user.save(function (err) {
            if (err) { return console.log(err); }
            req.flash('success','Password changed')
            return res.redirect('/login');
        });
        
    }
})
    
})

app.get('/logout',function(req,res){
    req.session.loggedIn = false;
    req.session.userId = undefined;
    req.session.username = undefined;
    res.redirect('/shoes');
})

app.get("/shoes",function(req,res){
    shoe.find({},function(err,shoes){
        if(err){
            console.log(err);
        } else{
            res.render("index",{shoes:shoes});
        }
    });
});

app.get("/shoes/new",isLoggedIn,function(req,res){
    res.render("new");
});

app.post("/shoes",function(req,res){
    shoe.create(req.body.shoe,function(err,newshoes){
        if(err){
            console.log(err);
        } else{
            newshoes.author.id = currentUserId;
            newshoes.author.name = currentUser;
            newshoes.save();
            req.flash('success','shoe added successfully');
            res.redirect("/shoes");
        }
    });
});

 //Search
 app.post('/getSN',async(req,res)=>{
    let payload=req.body.payload.trim();
    // console.log(payload);
    let search = await shoe.find({title:{$regex:new RegExp('^'+payload+'.*','i')}}).exec();
    search=search.slice(0,10);
    res.send({payload: search});
 })


app.get("/shoes/:id",function(req,res){
    shoe.findById(req.params.id,function(err,foundshoe){
        if(err){
            res.redirect("/shoes");
        } else{
            res.render("show",{shoe:foundshoe,userId:currentUserId});
        }
    });
});

app.get("/shoes/:id/edit",checkshoeOwner,function(req,res){
    shoe.findById(req.params.id,function(err,foundshoe){
        if(err){
            res.redirect("/shoes");
        } else{
            res.render("edit",{shoe:foundshoe});
        }
    });
});

app.put("/shoes/:id",function(req,res){
    req.body.shoe.body = req.sanitize(req.body.shoe.body);
    shoe.findByIdAndUpdate(req.params.id,req.body.shoe,function(err,updatedshoe){
        if(err){
            res.redirect("/shoes");
        } else{
            req.flash('success','shoe updated successfully');
            res.redirect("/shoes/"+ req.params.id);
        }
    });
});

app.delete("/shoes/:id",checkshoeOwner,function(req,res){
    shoe.findByIdAndRemove(req.params.id,function(err){
        if(err){
            res.redirect("/shoes");
        } else{
            req.flash('success','shoe deleted successfully');
            res.redirect("/shoes");
        }
    });
});

function isLoggedIn(req,res,next){
    if(req.session.loggedIn){
        return next();
    }
    req.flash('error','Please Login!');
    res.redirect("/login");
}

function checkshoeOwner(req,res,next){
    if(req.session.loggedIn){
        shoe.findById(req.params.id,function(err,foundshoe){
            if(err || !foundshoe){
                req.flash('error','shoe not found!');
                res.redirect('/shoe');
            }else{
                if(foundshoe.author.id == currentUserId){
                    next();
                } else{
                    req.flash('error','You have not permission to do that.');
                    res.redirect('/shoes');
                }
            }
        });
    }else{
        req.flash('error','Please Login!');
        res.redirect("/login");
    }
    
}

app.listen(3000,function(){
    console.log("Server has Started...");
});
