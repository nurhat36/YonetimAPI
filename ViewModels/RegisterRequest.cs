namespace YonetimAPI.ViewModels
{
    public class RegisterRequest
    {
        public string UserName { get; set; }
        public IFormFile ProfileImage { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
