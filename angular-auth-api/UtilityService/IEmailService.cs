using angular_auth_api.Models;

namespace angular_auth_api.UtilityService
{
    public interface IEmailService
    {
        void SendEmail(EmailModel email);
    }
}
