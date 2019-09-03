export const getHubInfo = async (hubUrl: string) => {
  const response = await fetch(`${hubUrl}/hub_info`)
  const data = await response.json()
  return data
}

export const getHubPrefix = async (hubUrl: string) => {
  const { read_url_prefix } = await getHubInfo(hubUrl)
  return read_url_prefix
}
