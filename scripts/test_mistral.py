from mistralai.client import Mistral
import os

client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])

res = client.chat.complete(
    model="mistral-small-latest",
    messages=[{"role": "user", "content": "Dis bonjour en JSON"}]
)

print(res.choices[0].message.content)  # .content est un attribut, pas une clé dict