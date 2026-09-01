using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

namespace _1202demoapp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KargoSorguController : ControllerBase
    {
        [HttpGet("takip/{takipNo}")]
        public IActionResult GetKargoDurumu(string takipNo)
        {
            // ❌ ZAAFİYET 1: SQL Injection (Kullanıcıdan gelen 'takipNo' doğrudan sorgu dizesine ekleniyor)
            string query = "SELECT * FROM KargoGonderileri WHERE TakipNo = '" + takipNo + "'";

            // ❌ KOD HATASI 2: Resource Leak (SqlConnection ve SqlDataReader 'using' bloğuna alınmamış, açık kalıyor)
            SqlConnection connection = new SqlConnection("Server=localhost;Database=SuratKargoDB;Trusted_Connection=True;");
            SqlCommand command = new SqlCommand(query, connection);
            
            connection.Open();
            SqlDataReader reader = command.ExecuteReader();

            if (reader.Read())
            {
                string alici = reader["AliciAdi"].ToString();
                return Ok(new { TakipNo = takipNo, Alici = alici });
            }

            return NotFound("Kargo bulunamadı.");
        }
    }
}
