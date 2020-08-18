from PIL import Image

size = 128, 128

def create_thumbnail(img, name):

  image  = Image.open(img)
  width  = image.size[0]
  height = image.size[1]

  aspect = width / float(height)

  if width >= height:
    ideal_size = height
  else:
    ideal_size = width

  ideal_aspect = 1

  if aspect > ideal_aspect:
      # Then crop the left and right edges:
      new_width = int(ideal_aspect * height)
      offset = (width - new_width) / 2
      resize = (offset, 0, width - offset, height)
  else:
      # ... crop the top and bottom:
      new_height = int(width / ideal_aspect)
      offset = (height - new_height) / 2
      resize = (0, offset, width, height - offset)

  thumb = image.crop(resize).resize((ideal_size, ideal_size), Image.ANTIALIAS)
  thumb.thumbnail(size, Image.ANTIALIAS)
  thumb.save(name, "JPEG")
  image.close()
  thumb.close()