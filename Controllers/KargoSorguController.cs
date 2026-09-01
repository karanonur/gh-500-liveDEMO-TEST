using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

namespace _1202demoapp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KargoSorguController : ControllerBase
    {
        [HttpGet("sorgula")]
        public IActionResult KargoSorgula()
        {
            // ❌ CodeQL Taint Engine'in doğrudan yakaladığı HTTP Girdisi (Source)
            string takipNo = Request.Query["takipNo"];

            // ❌ ZAAFİYET 1: SQL Injection (String birleştirme)
            string query = "SELECT * FROM KargoGonderileri WHERE TakipNo = '" + takipNo + "'";

            // ❌ ZAAFİYET 2: Resource Leak (using kullanılmamış, açık bağlantı)
            SqlConnection connection = new SqlConnection("Server=localhost;Database=SuratKargoDB;Trusted_Connection=True;");
            SqlCommand command = new SqlCommand(query, connection);
            
            connection.Open();
            SqlDataReader reader = command.ExecuteReader(); // Sink (Hedef)

            return Ok("Sorgu çalıştırıldı.");
        }
    }
}
