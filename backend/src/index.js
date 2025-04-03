import express from 'express'
import cors from 'cors'

async function main() {
  const hostname = 'localhost'
  const port = 3000

  const app = express()

  app.use(express.json())
  app.use(cors())

  app.get('/', (req, res) => {
    res.send({
      success: true,
      statuscode: 200,
      body: 'Bem-vindo ao MyGastronomy!'
    })
  })

  app.listen(port, () => {
    console.log(`Server running on: http://${hostname}:${port}`)
  })
}
main()