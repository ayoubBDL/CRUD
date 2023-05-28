using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using server.helpers;
using server.Models;

namespace server.Controllers
{
    [Route("[controller]")]
    public class UserController : Controller
    {
        private readonly ServerDbContext _serverDbContext;

        public UserController(ServerDbContext  serverDbContext)
        {
            _serverDbContext = serverDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj){
            if(userObj == null){
                Console.WriteLine("userObj is null");
                return BadRequest();
            }
            var user = await _serverDbContext.Users.FirstOrDefaultAsync(u => u.UserName == userObj.UserName); 
            if(user == null){
                return NotFound(new {Message = "User not found"});
            }

            if(!BCrypt.Net.BCrypt.Verify(userObj.Password, user.Password)){
                return NotFound(new {Message = "Password Incorrect"});
            }

            user.Token = CreateJwt(user);

            return Ok(
                new {Message = "Login Success!",
                Token = user.Token}
            );
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj){
            if(userObj == null){
                return BadRequest();
            }

            //Check Username
            if(await CheckUsernameExistAsync(userObj.UserName)){
                return BadRequest(new {Message = "Username already taken!"});
            }
            
            //Check Email
            if(await CheckEmailExistAsync(userObj.Email)){
                return BadRequest(new {Message = "Email already taken!"});
            }

            //Check Password Strength
            var pass = CheckPasswordStrong(userObj.Password);
            if(!string.IsNullOrEmpty(pass)){
                return BadRequest(new {Message = pass.ToString()});
            }

            // userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Password = BCrypt.Net.BCrypt.HashPassword(userObj.Password, 16);
            
            userObj.Role = "User";
            userObj.Token = "";
            await _serverDbContext.AddAsync(userObj); 
            await _serverDbContext.SaveChangesAsync();
            
            return Ok(new {Message = "User Registered!"});
        }

        private Task<bool> CheckUsernameExistAsync(string userName)=>_serverDbContext.Users.AnyAsync(u => u.UserName == userName);
        private Task<bool> CheckEmailExistAsync(string email)=>_serverDbContext.Users.AnyAsync(u => u.Email == email);
        private string CheckPasswordStrong(string password){
            StringBuilder sb = new StringBuilder();
            if (password. Length < 8)
            sb. Append("Minimum password length should be 8"+Environment. NewLine);
            if (!(Regex. IsMatch (password, "[a-z]") && Regex. IsMatch (password, "[A-Z]")
            && Regex. IsMatch (password, "[0-9]")))
            sb. Append("Password should be Alphanumeric" + Environment. NewLine);
            // if(!Regex. IsMatch(password, "[<,>,@, !, #, $, %, ^, &, *, (, ), _, +, \\[, \\], {, }, ?, : , ; , ',\\, . ,/,~,=]"));
            // sb. Append("Password should contain special chars"+Environment. NewLine);

            return sb.ToString();   
        }

        private string CreateJwt(User user){
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("this is my secret...");
            var identity = new ClaimsIdentity(new Claim[]{
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, user.UserName),
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);

        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers(){
            return Ok(await _serverDbContext.Users.ToListAsync());
        }
    }
}