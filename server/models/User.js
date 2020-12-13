const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true, // space를 없애주는 역할
    unique: 1
  },
  password: {
    type: String,
    minlength: 5
  },
  lastname: {
    type: String,
    maxlength: 50
  },
  role: {
    type: Number,
    default: 0
  },
  image: String,   // 이런 식으로도 가능
  token: {
    type: String
  },
  tokenExp: {
    type: Number
  }
})

userSchema.pre('save', function( next ){  // pre 도 mongoose에서 가져온 메서드. 
  var user = this;

  // 비밀번호가 수정될 때
  if(user.isModified('password')) {

    // 비밀번호를 암호화 시킨다.
    bcrypt.genSalt(saltRounds, function(err, salt){
      if(err) return next(err);

      bcrypt.hash(user.password, salt, function(err, hash) {
        if(err) return next(err);
        user.password = hash;
        next();
        // store hash in your password DB.
      })
    })
  } else {
    next();
  }
});   // index.js 의 유저정보를 저장하기 전에 무언가 하겠다!는 뜻

userSchema.methods.comparePassword = function(plainPassword, cb) {
  // plainPassword 1234567, 암호화된 비밀번호 check
  bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
    if(err) return cb(err);
    cb(null, isMatch);
  });
};

userSchema.methods.generateToken = function (cb) {

  var user = this;

  // jsonwebtoken을 이용해서 token을 생성하기

  var token = jwt.sign(user._id.toHexString(), 'secretToken');

  user.token = token
  user.save(function(err, user) {
    if(err) return cb(err);
    cb(null, user);
  })
}

userSchema.statics.findByToken = function(token, cb) {
  var user = this;

  // 토큰을 decode 한다.
  jwt.verify(token, 'secretToken', function(err, decoded) {
    // 유저 아이디를 이용해서 유저를 찾은 다음에
    // 클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인

    user.findOne({ "_id": decoded, "token": token }, function(err, user) {
      if(err) return cb(err);
      cb(null, user);
    })
  })
}

const User = mongoose.model('User', userSchema);  // 스키마를 모델로 감싸줌

module.exports = { User }  // 이 모델을 다른 파일에서도 사용할 수 있도록